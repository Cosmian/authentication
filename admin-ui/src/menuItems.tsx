import {
    AppstoreOutlined,
    ClockCircleOutlined,
    CrownOutlined,
    DashboardOutlined,
    KeyOutlined,
    RobotOutlined,
    SafetyOutlined,
} from "@ant-design/icons";

export interface MenuItem {
    key: string;
    label: string;
    icon?: React.ReactNode;
    children?: MenuItem[];
    superAdminOnly?: boolean;
    /** When true, visible only if the user administers the selected realm */
    requiresRealmOwnership?: boolean;
}

export const menuItems: MenuItem[] = [
    {
        key: "/",
        label: "Dashboard",
        icon: <DashboardOutlined />,
    },
    {
        key: "/realms",
        label: "Realms",
        icon: <AppstoreOutlined />,
        superAdminOnly: true,
    },
    {
        key: "/admins",
        label: "Admins",
        icon: <CrownOutlined />,
        requiresRealmOwnership: true,
    },
    {
        key: "/credentials",
        label: "Credentials",
        icon: <KeyOutlined />,
    },
    {
        key: "/machine-credentials",
        label: "Machine Creds",
        icon: <RobotOutlined />,
        superAdminOnly: true,
    },
    {
        key: "/sessions",
        label: "Sessions",
        icon: <ClockCircleOutlined />,
    },
    {
        key: "/oidc-clients",
        label: "OIDC Clients",
        icon: <SafetyOutlined />,
    },
];
