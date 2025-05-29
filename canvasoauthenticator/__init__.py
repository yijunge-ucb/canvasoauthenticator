import aiohttp

from traitlets import List, Unicode, default
from oauthenticator.generic import GenericOAuthenticator
from tornado import web
from tornado.httputil import url_concat
from inspect import isawaitable
import jwt
import json

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
        self.groups_url = f"{self.canvas_url}api/v1/users/self/groups"
        self.courses_url = f"{self.canvas_url}api/v1/courses"

        self.extra_params = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            # We set replace_tokens=1 to prevent tokens from accumulating.
            # https://github.com/instructure/canvas-lms/blob/release/2022-08-03.12/spec/controllers/oauth2_provider_controller_spec.rb#L520
            "replace_tokens": 1,
        }
        
    
    async def fetch_all_pages(self, url, access_token, token_type):
        """Fetch all paginated Canvas API results using httpfetch (which returns parsed JSON)."""
        all_data = []

        while url:
            headers = self.build_userdata_request_headers(access_token, token_type)

            resp_data = await self.httpfetch(
                url,
                label=f"Fetching paginated Canvas data from: {url}",
                method="GET",
                headers=headers,
                validate_cert=self.validate_server_cert,
                parse_json=True,  
            )

            if isinstance(resp_data, list):
                all_data.extend(resp_data)
            elif resp_data:
                all_data.append(resp_data)

            raw_resp = await self.httpfetch(
                url,
                label="Inspecting Link headers for pagination",
                method="GET",
                headers=headers,
                validate_cert=self.validate_server_cert,
                parse_json=False,
            )

            link_header = raw_resp.headers.get("Link", "")
            next_url = None
            for part in link_header.split(","):
                if 'rel="next"' in part:
                    next_url = part.split(";")[0].strip(" <>")
                    break

            url = next_url

        return all_data


    async def token_to_user(self, token_info):
        """
        Extended version that returns user info + Canvas groups + courses.
        """
        if self.userdata_from_id_token:
            # Use id token instead of exchanging access token with userinfo endpoint.
            id_token = token_info.get("id_token", None)
            if not id_token:
                raise web.HTTPError(
                    500,
                    f"An id token was not returned: {token_info}\nPlease configure authenticator.userdata_url",
                )
            try:
                # Here we parse the id token. Note that per OIDC spec (core v1.0 sect. 3.1.3.7.6) we can skip
                # signature validation as the hub has obtained the tokens from the id provider directly (using
                # https). Google suggests all token validation may be skipped assuming the provider is trusted.
                # https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                # https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo
                return jwt.decode(
                    id_token,
                    audience=self.client_id,
                    options=dict(
                        verify_signature=False, verify_aud=True, verify_exp=True
                    ),
                )
            except Exception as err:
                raise web.HTTPError(
                    500, f"Unable to decode id token: {id_token}\n{err}"
                )

        access_token = token_info["access_token"]
        token_type = token_info["token_type"]

        if not self.userdata_url:
            raise ValueError(
                "authenticator.userdata_url is missing. Please configure it."
            )

        url = url_concat(self.userdata_url, self.userdata_params)
        if self.userdata_token_method == "url":
            url = url_concat(url, dict(access_token=access_token))

        user_info = await self.httpfetch(
            url,
            "Fetching user info...",
            method="GET",
            headers=self.build_userdata_request_headers(access_token, token_type),
            validate_cert=self.validate_server_cert,
        )
        
        self_groups = await self.fetch_all_pages(self.groups_url, access_token, token_type)
        courses = await self.fetch_all_pages(self.courses_url, access_token, token_type)
        course_group_names = self.groups_from_canvas_courses(courses)
        self_group_names = self.groups_from_canvas_groups(self_groups)
        groups = course_group_names + self_group_names
       
    
        return {
            'user': user_info,
            "groups": groups,
            "courses": courses
        }


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
    
    def build_auth_state_dict(self, token_info, user_info):
        # We know for sure the `access_token` key exists, otherwise we would have errored out already
        access_token = token_info["access_token"]

        refresh_token = token_info.get("refresh_token", None)
        id_token = token_info.get("id_token", None)
        scope = token_info.get("scope", "")

        if isinstance(scope, str):
            scope = scope.split(" ")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "id_token": id_token,
            "scope": scope,
            # Save the full token response
            # These can be used for user provisioning in the Lab/Notebook environment.
            "token_response": token_info,
            # store the whole user model in auth_state too
            self.user_auth_state_key: user_info.get("user", {}),
            "courses": user_info.get("courses", []),
            "groups": user_info.get("groups", []),
        }

    async def _token_to_auth_model(self, token_info):
        """
        Turn a token into the user's `auth_model` to be returned by :meth:`.authenticate`.

        Common logic shared by :meth:`.authenticate` and :meth:`.refresh_user`.
        """

        # use the access_token to get userdata info
        user_info = await self.token_to_user(token_info)
        # extract the username out of the user_info dict and normalize it
        username = self.user_info_to_username(user_info.get("user", {}))
        username = self.normalize_username(username)

        auth_state = self.build_auth_state_dict(token_info, user_info)
        if isawaitable(auth_state):
            auth_state = await auth_state
        if self.modify_auth_state_hook is not None:
            auth_state = await self._call_modify_auth_state_hook(auth_state)
        # build the auth model to be read if authentication goes right
        auth_model = {
            "name": username,
            "admin": True if username in self.admin_users else None,
            "auth_state": auth_state,
        }

        # update the auth_model with info to later authorize the user in
        # check_allowed, such as admin status and group memberships
        auth_model = await self.update_auth_model(auth_model)
        if self.manage_groups:
            auth_model = await self._apply_managed_groups(auth_model)
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