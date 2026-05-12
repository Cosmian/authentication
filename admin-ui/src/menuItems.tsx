import {
    AppstoreOutlined,
    ClockCircleOutlined,
    CrownOutlined,
    DashboardOutlined,
    KeyOutlined,
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
        key: "/sessions",
        label: "Sessions",
        icon: <ClockCircleOutlined />,
    },
];
