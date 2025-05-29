import aiohttp

from traitlets import List, Unicode, default
from oauthenticator.generic import GenericOAuthenticator
from urllib.parse import urlencode
from tornado import web


class CanvasOAuthenticator(GenericOAuthenticator):
    """
    Canvas OAuth2 based authenticator for JupyterHub.

    Assigns users to groups based on their course enrollments.
    To refresh, the user has to re-login.
    """

    # The name of the user key expected to be present in `auth_state`
    user_auth_state_key = "canvas_user"

    @default("auth_state_groups_key")
    def _auth_state_groups_key_default(self):
        # Do not set this within "canvas_user", since Canvas is not providing groups.
        return f"groups"

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

    async def get_refresh_token(self, params):
        """
        Makes a "POST" request to `self.token_url`, with the parameters received as argument.

        Returns:
            the JSON response to the `token_url` the request as described in
            https://www.rfc-editor.org/rfc/rfc6749#section-5.1

        Called by :meth:`.authenticate` and :meth:`.refresh_user`.
        """

        token_info = await self.httpfetch(
            self.token_url,
            method="POST",
            headers=self.build_token_info_request_headers(),
            body=urlencode(params).encode("utf-8"),
            validate_cert=self.validate_server_cert,
        )

        if "error_description" in token_info:
            raise web.HTTPError(
                403,
                f'An access token was not returned: {token_info["error_description"]}',
            )
        elif "access_token" not in token_info:
            raise web.HTTPError(500, f"Bad response: {token_info}")

        return token_info

    async def get_canvas_items(self, access_token, url):
        """
        Get paginated items from Canvas.
        https://canvas.instructure.com/doc/api/file.pagination.html
        """

        headers = dict(Authorization=f"Bearer {access_token}")
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
                    data += await self.get_canvas_items(access_token, url)

        return data

    async def get_courses(self, access_token):
        """
        Get list of active courses for the current user.

        See https://canvas.instructure.com/doc/api/courses.html#method.courses.index
        """
        url = f"{self.canvas_url}/api/v1/courses"

        data = await self.get_canvas_items(access_token, url)

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

    async def update_auth_model(self, auth_model):
        """
        Ensure groups are set in auth_state for JupyterHub group management.
        This is called after authenticate and before group sync.
        """
        auth_model = await super().update_auth_model(auth_model)

        access_token = auth_model["auth_state"]["access_token"]

        refresh_token = auth_model["auth_state"]["refresh_token"]

        refresh_token_params = self.build_refresh_token_request_params(refresh_token)
        token_info = await self.get_refresh_token(refresh_token_params)
        new_access_token = token_info.get("access_token")

        if not new_access_token:
            self.log.error("Failed to refresh access token.")
            raise web.HTTPError(500, "Failed to refresh access token.")

        courses = await self.get_courses(new_access_token)

        # Preserve courses in auth_state for later use by the spawner
        auth_model["auth_state"]["courses"] = courses

        if self.manage_groups:
            course_group_names = self.groups_from_canvas_courses(courses)

            self_groups = await self.get_self_groups(new_access_token)
            self_group_names = self.groups_from_canvas_groups(self_groups)

            groups = course_group_names + self_group_names
            auth_model["auth_state"][self.auth_state_groups_key] = groups
        auth_model["auth_state"]["access_token"] = new_access_token
        auth_model["auth_state"]["token_response"]["access_token"] = new_access_token
        return auth_model

    def normalize_username(self, username):
        """Strip the user's email domain, if enabled."""
        username = username.lower()
        if self.strip_email_domain and username.endswith("@" + self.strip_email_domain):
            return username.split("@")[0]
        return username

    async def pre_spawn_start(self, user, spawner):
        """Pass oauth data to spawner via OAUTH2_ prefixed env variables."""
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
