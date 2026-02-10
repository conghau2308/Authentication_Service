package com.Authentication.AuthService.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ClientPermission {
    ALL("all", "Full access to everything"),
    MANAGE_SECRETS("manage_secrets", "Create, view, and revoke client secrets"),
    VIEW_SECRETS("view_secrets", "View secret hints and metadata"),
    MANAGE_SETTINGS("manage_settings", "Update client configuration"),
    MANAGE_MEMBERS("manage_members", "Add/remove team members"),
    DELETE_CLIENT("delete_client", "Delete the client application"),
    VIEW("view", "View client information only");

    private final String value;
    private final String description;
}
