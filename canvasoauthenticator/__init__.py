import aiohttp

from traitlets import List, Unicode, default
from oauthenticator.generic import GenericOAuthenticator


class CanvasOAuthenticator(GenericOAuthenticator):
    """
    Canvas OAuth2 based authenticator for JupyterHub.

    Assigns users to groups based on their course enrollments.
    To refresh, the user has to re-login.
    """

    strip_email_domain = Unicode(
        "",
        config=True,
        help="""
        Strip this domain from user emails when making their JupyterHub user name.

        For example, if almost all your users have emails of form username@berkeley.edu,
        you can set this to 'berkeley.edu'. A canvas user with email yuvipanda@berkeley.edu
        will get a JupyterHub user name of 'yuvipanda', while a canvas user with email
        yuvipanda@gmail.com will get a JupyterHub username of 'yuvipanda@gmail.com'.

        By default, *no* domain stripping is performed, and the JupyterHub username
        is the primary email of the canvas user.
        """,
    )

    canvas_url = Unicode(
        "",
        config=True,
        help="""
        URL to canvas installation to use for authentication.

        Must have a trailing slash
        """,
    )

    canvas_course_key = Unicode(
        "",
        config=True,
        help="""
        Key to lookup course identifier from Canvas course data.
        See https://canvas.instructure.com/doc/api/courses.html.

        This might be 'sis_course_id', 'course_code', 'id', etc.

        id examples: 12345, 23456
        sis_course_id examples: CRS:MATH-98-2021-C, CRS:CHEM-1A-2021-D, CRS:PHYSICS-77-2022-C
        course_code examples: "Math 98", "Chem 1A Fall 2021", "PHYSICS 77-LEC-001"
        """,
    )

    @default("canvas_course_key")
    def _default_canvas_course_key(self):
        """
        The default is 'id', an integer which doesn't convey anything about the
        course, though it is present in the course URL.

        'sis_course_id' is the most useful, in that it is predictable and human
        readable, but some student enrollment types cannot read it in common
        deployments.

        'course_code' contain human-readable information, cannot be overridden
        by nicknames, and the user won't be excluded from reading it, but it is
        not garanteed to be unique.
        """
        return "id"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not self.canvas_url:
            raise ValueError("c.CanvasOAuthenticator.canvas_url must be set")

        # canvas_url must have a trailing slash
        if self.canvas_url[-1] != "/":
            raise ValueError(
                "c.CanvasOAuthenticator.canvas_url must have a trailing slash"
            )

        self.token_url = f"{self.canvas_url}login/oauth2/token"
        self.userdata_url = f"{self.canvas_url}api/v1/users/self/profile"

        self.extra_params = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            # We set replace_tokens=1 to prevent tokens from accumulating.
            # https://github.com/instructure/canvas-lms/blob/release/2022-08-03.12/spec/controllers/oauth2_provider_controller_spec.rb#L520
            "replace_tokens": 1,
        }

    async def get_canvas_items(self, token, url):
        """
        Get paginated items from Canvas.
        https://canvas.instructure.com/doc/api/file.pagination.html
        """
        headers = dict(Authorization=f"Bearer {token}")
        data = []

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=self.extra_params) as r:
                if r.status != 200:
                    raise Exception(
                        f"error fetching items {url} -- {r.status} -- {r.text()}"
                    )
                data = await r.json()
                if "next" in r.links.keys():
                    url = r.links["next"]["url"]
                    data += await self.get_canvas_items(token, url)

        return data

    async def get_courses(self, token):
        """
        Get list of active courses for the current user.

        See https://canvas.instructure.com/doc/api/courses.html#method.courses.index
        """
        url = f"{self.canvas_url}/api/v1/courses"

        data = await self.get_canvas_items(token, url)

        return data

    async def get_self_groups(self, token):
        """
        Get list of active groups for the current user.

        See https://canvas.instructure.com/doc/api/groups.html#method.groups.index
        """
        url = f"{self.canvas_url}/api/v1/users/self/groups"

        data = await self.get_canvas_items(token, url)

        return data

    def format_jupyterhub_group(self, *terms):
        """
        Return a group name assembled from provided terms.
        """
        return "::".join(map(str, terms))

    def groups_from_canvas_courses(self, courses):
        """
        Create group identifiers for each canvas course the user is enrolled in:

          course::{course_id}
          course::{course_id}::enrollment_type::{enrollment_type}
        """
        groups = []

        for course in courses:
            course_id = course.get(self.canvas_course_key, None)
            if course_id is None:
                continue

            # Creates `course::{course_id}`
            groups.append(self.format_jupyterhub_group("course", course_id))

            # examples: [{'enrollment_state': 'active', 'role': 'TeacherEnrollment', 'role_id': 1773, 'type': 'teacher', 'user_id': 12345}],
            # https://canvas.instructure.com/doc/api/courses.html#method.courses.index
            # There may be multiple (or even duplicate) enrollments per course
            enrollment_types = set(
                map(lambda x: x.get("type", None), course.get("enrollments", []))
            )

            # Creates `course::{course_id}::enrollment_type::{enrollment_type}`
            for enrollment_type in enrollment_types:
                groups.append(
                    self.format_jupyterhub_group(
                        "course", course_id, "enrollment_type", enrollment_type
                    )
                )

        return groups

    def groups_from_canvas_groups(self, self_groups):
        """
        Create group identifiers for each canvas group the user is a member of.

        Formatted as {context_type}::{context_id}::group::{name}
        e.g. `course::12345::group::mygroup1`
             `account::23456::group::mygroup1`
        """
        # There is no way to distinguish if the same group name appears in
        # multiple group sets. We use a set to eliminate duplicates.
        groups = set()

        for group in self_groups:
            if "name" not in group:
                continue
            name = group.get("name")
            # `context_type` might be "Course" or "Account"
            context_type = group.get("context_type").lower()
            # The corresponding id field, e.g. `course_id` or `account_id`
            context_id_field = context_type + "_id"
            context_id = group.get(context_id_field, 0)
            groups.add(
                self.format_jupyterhub_group(context_type, context_id, "group", name)
            )

        return list(groups)

    async def authenticate(self, handler, data=None):
        """Augment base user auth info with course info."""
        user = await super().authenticate(handler, data)
        old_auth_state = user.get("auth_state")
        auth_state = {
            "oauth_user": old_auth_state.get("oauth_user", {}),
        }
        user["auth_state"] = auth_state

        access_token = user["auth_state"]["access_token"]

        # If the authenticator's concept of group membership is to be preserved
        if self.manage_groups:
            # Create groups based on Canvas courses
            courses = await self.get_courses(access_token)
            course_group_names = self.groups_from_canvas_courses(courses)

            # Create groups based on Canvas groups
            self_groups = await self.get_self_groups(access_token)
            self_group_names = self.groups_from_canvas_groups(self_groups)

            user["groups"] = course_group_names + self_group_names

        self.log.info(f"INFO: user after authentication is {user}")
        return user

    def normalize_username(self, username):
        """Strip the user's email domain, if enabled."""
        username = username.lower()
        if self.strip_email_domain and username.endswith("@" + self.strip_email_domain):
            return username.split("@")[0]
        return username

    async def pre_spawn_start(self, user, spawner):
        """Pass oauth data to spawner via OAUTH2_ prefixed env variables."""
        self.log.info(f"INFO: user pre spawn is {user}")
        self.log.info(f"INFO: user.get_auth_state() is {user.get_auth_state()}")
        auth_state = yield user.get_auth_state()
        if not auth_state:
            return
        if "access_token" in auth_state:
            spawner.environment["OAUTH2_ACCESS_TOKEN"] = auth_state["access_token"]
        # others are lti_user_id, id, integration_id
        if "oauth_user" in auth_state:
            for k in ["login_id", "name", "sortable_name", "primary_email"]:
                if k in auth_state["oauth_user"]:
                    spawner.environment[f"OAUTH2_{k.upper()}"] = auth_state[
                        "oauth_user"
                    ][k]
