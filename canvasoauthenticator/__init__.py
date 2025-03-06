import aiohttp

from traitlets import List, Unicode, default
from oauthenticator.generic import GenericOAuthenticator

import os



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

        return user

    def normalize_username(self, username):
        """Strip the user's email domain, if enabled."""
        username = username.lower()
        if self.strip_email_domain and username.endswith("@" + self.strip_email_domain):
            return username.split("@")[0]
        return username
    
    async def connect_to_database(self, user, password, dbname, host, port):
        """Connect to the PostgreSQL database asynchronously."""
        try:
            # Establish connection using asyncpg
            connection = await asyncpg.connect(
                user=user,
                password=password,
                database=dbname,
                host=host,
                port=port
            )
            print(f"Connected to database {dbname}.")
            return connection
        except Exception as e:
            print(f"Error: Unable to connect to the database. {e}")
            return None

    async def create_table(self, connection, table_name):
        """Create the table if it does not exist."""
        query = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id SERIAL PRIMARY KEY, 
            username VARCHAR(255) NOT NULL, 
            last_login TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
        try:
            await connection.execute(query)
            print(f"Table '{table_name}' created or already exists.")
        except Exception as e:
            print(f"Error creating table: {e}")

    async def insert_or_update_user(self, connection, table_name, username):
        """Insert a user or update if the user exists."""
        # First, check if the user already exists in the table
        check_query = f"SELECT COUNT(*) FROM {table_name} WHERE username = $1;"
        result = await connection.fetchval(check_query, username)

        if result == 0:
            # If the user does not exist, insert a new user
            insert_query = f"INSERT INTO {table_name} (username) VALUES ($1) RETURNING id;"
            new_user_id = await connection.fetchval(insert_query, username)
            print(f"Inserted new user with ID: {new_user_id}")
        else:
            # If the user exists, update the last_login field
            update_query = f"UPDATE {table_name} SET last_login = CURRENT_TIMESTAMP WHERE username = $1;"
            await connection.execute(update_query, username)
            print(f"Updated last login for user: {username}")
    
    async def print_all_entries(self, connection, table_name):
        """Print out all the entries in the table."""
        query = f"SELECT * FROM {table_name};"
        rows = await connection.fetch(query)
        
        print(f"Entries in table '{table_name}':")
        for row in rows:
            print(dict(row))



    async def update_user_database(self, user):
        """
        Connect to the cloudsql database.
        Create the table if it does not already exist.
        Insert/update the authenticated user's last login info.
        """
        # Get the database connection details from environment variables
        db_user = os.getenv("DB_USER")
        db_password = os.getenv("DB_PASSWORD")
        db_name = os.getenv("DB_NAME")
        db_host = os.getenv("DB_HOST")
        db_port = os.getenv("DB_PORT")
        pod_namespace = os.getenv("POD_NAMESPACE")

        print("JupyterHub is starting! Welcome to the JupyterHub server.")
        print("Trying to connect to the Cloud Postgres database.")
        print(f"Username: {user.name}")

        # Get table name
        hub, prod_or_staging = pod_namespace.split('-')
        table_name = "users_" + hub + "_" + prod_or_staging

        connection = await self.connect_to_database(db_user, db_password, db_name, db_host, db_port)
        if connection is None:
            return  # Exit if connection failed
    
        #  Create the table if it doesn't exist
        await self.create_table(connection, table_name)
    
        #  Insert or update user
        await self.insert_or_update_user(connection, table_name, self.normalize_username(user.name))
    
        # Print all entries in the table
        await self.print_all_entries(connection, table_name)

        # Close the connection
        await connection.close()


    async def pre_spawn_start(self, user, spawner):
        """Pass oauth data to spawner via OAUTH2_ prefixed env variables."""
        auth_state = yield user.get_auth_state()
        self.log.debug("debugging: trying to update database")
        self.log.info("info: trying to update database")
        self.log.warning("warning: trying to update database")

        # updating the database
        await self.update_user_database(user)

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
