package com.Authentication.AuthService.enums;

import java.util.Set;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ClientRole {
    OWNER("Owner", Set.of(
            ClientPermission.ALL)),
    ADMIN("Administrator", Set.of(
            ClientPermission.MANAGE_SECRETS,
            ClientPermission.MANAGE_SETTINGS,
            ClientPermission.MANAGE_MEMBERS,
            ClientPermission.VIEW)),
    DEVELOPER("Developer", Set.of(
            ClientPermission.VIEW_SECRETS,
            ClientPermission.MANAGE_SETTINGS,
            ClientPermission.VIEW));
// Nếu sau này cần audit trail khi hệ thống được phát triển hơn thì sẽ cần thêm phân quyền VIEW cho analyst
//     VIEWER("Viewer", Set.of(
//             ClientPermission.VIEW));
    
    private final String roleName;
    private final Set<ClientPermission> permissions;

    public boolean hasPermission(ClientPermission permission) {
        return permissions.contains(ClientPermission.ALL) || permissions.contains(permission);
    }

    public boolean canManageSecrets() {
        return hasPermission(ClientPermission.MANAGE_SECRETS);
    }
}
