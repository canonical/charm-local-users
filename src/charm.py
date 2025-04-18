#!/usr/bin/env python3
# Copyright 2021 Canonical
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Create and manage local user accounts and groups with Juju."""

import logging
import os

from local_users import (
    User,
    add_group,
    check_sudoers_file,
    configure_user,
    delete_user,
    get_group_users,
    get_lp_ssh_keys,
    group_exists,
    is_lp_user,
    is_unmanaged_user,
    parse_gecos,
    remove_group,
    rename_group,
    write_sudoers_file,
)
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

log = logging.getLogger(__name__)


class CharmLocalUsersCharm(CharmBase):
    """Charm the service."""

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self.on_install)
        self.framework.observe(self.on.config_changed, self.on_config_changed)
        self.framework.observe(self.on.stop, self.on_stop)
        self._stored.set_default(group="")

    def on_install(self, _):
        self.unit.status = ActiveStatus()

    def on_config_changed(self, _):
        """Create and update system users and groups to match the config.

        Ensure that the charm managed group exists on the unit.
        Remove any users in charm managed group who are not in the current 'users' config value.
        Resolve any differences between users listed in the config and their equivalent system
        users (i.e. change in GECOS or SSH public keys).
        Add any new users who are in UserList but not CharmManagedGroup.
        """
        # ensure that directory for home dir backups exists
        backup_path = self.config["backup-path"]
        if not os.path.exists(backup_path):
            os.makedirs(backup_path, mode=0o700)

        # configure charm managed group
        group = self.config["group"]
        if not group:
            self.unit.status = BlockedStatus("'group' config option value is required")
            return

        if not group_exists(group):
            if self._stored.group and self._stored.group != group:
                log.debug(
                    "renaming charm managed group: '%s' to '%s'",
                    self._stored.group,
                    group,
                )
                rename_group(self._stored.group, group)
            else:
                add_group(group)

        # save the current managed group name in StoredState so that the charm can detect if rename
        # is needed on future config_changed events
        self._stored.group = group

        # parse user list from the config
        users = self.config["users"].splitlines()
        output = self.prepare_users(users)
        if isinstance(output, str):
            error_msg = output
            log.error(error_msg)
            self.unit.status = BlockedStatus(error_msg)
            return

        userlist = output

        # check if there are any conflicts between the user list in the config and on the unit,
        # back out if so unless the config flag 'allow-existing-users' is set to True
        unmanaged_users = []
        for user in userlist:
            if is_unmanaged_user(user.name, group):
                unmanaged_users.append(user.name)
        if len(unmanaged_users) > 0:
            msg = "users {} already exist and are not members of {}".format(unmanaged_users, group)
            if not self.config["allow-existing-users"]:
                log.error(msg)
                self.unit.status = BlockedStatus(msg)
                return
            log.warning(msg)

        # remove users that are no longer in the config but still exist on the unit
        current_users = get_group_users(group)
        config_usernames = [u.name for u in userlist]
        users_to_remove = set(current_users) - set(config_usernames)
        if users_to_remove:
            log.debug("removing users: %s", list(users_to_remove))
            for u in users_to_remove:
                delete_user(u, backup_path)

        # configure user accounts specified in the config
        authorized_keys_path = self.config["ssh-authorized-keys"]
        for user in userlist:
            configure_user(user, group, authorized_keys_path)

        # Configure custom /etc/sudoers.d file
        sudoers = self.config["sudoers"]
        error = check_sudoers_file(sudoers)
        if error:
            msg = "parse error in sudoers config, check juju debug-log for more information"
            self.unit.status = BlockedStatus(msg)
            return
        else:
            write_sudoers_file(sudoers)

        self.unit.status = ActiveStatus()

    def prepare_users(self, users: list) -> list:
        """Return prepared user list from users config.

        Return error message string on error.
        """
        usernames = []
        userlist = []
        user_objects = {}

        for line in users:
            u = line.split(";")
            if len(u) != 3 or not u[0]:
                error_msg = "'users' config option contains invalid entries"
                return error_msg
            usernames.append(u[0])

        unique_users = list(set(usernames))
        log.debug(f"List of users: {unique_users}")

        for username in unique_users:
            user_objects[username] = {}
            user_objects[username]["authorized_keys"] = []

        for line in users:
            username, gecos, ssh_key_input = line.split(";")
            user_objects[username]["name"] = username
            user_objects[username]["gecos"] = parse_gecos(gecos)
            if is_lp_user(ssh_key_input):
                lp_user = ssh_key_input
                lp_ssh_keys = get_lp_ssh_keys(lp_user)
                if lp_ssh_keys is None:
                    error_msg = f"Unable to retrieve key(s) for provided Launchpad user {lp_user}"
                    return error_msg
                user_objects[username]["authorized_keys"].extend(lp_ssh_keys)
            else:
                ssh_key = ssh_key_input
                user_objects[username]["authorized_keys"].append(ssh_key)

        for username in unique_users:
            user = User(
                user_objects[username]["name"],
                user_objects[username]["gecos"],
                user_objects[username]["authorized_keys"],
            )
            userlist.append(user)

        return userlist

    def on_stop(self, _):
        """Remove charm managed users and group from the machine."""
        group = self.config["group"]
        backup_path = self.config["backup-path"]
        users = get_group_users(group)
        for user in users:
            delete_user(user, backup_path)
        remove_group(group)
        self.unit.status = ActiveStatus()


if __name__ == "__main__":
    main(CharmLocalUsersCharm)
