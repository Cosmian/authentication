import {
    ClockCircleOutlined,
    DashboardOutlined,
    KeyOutlined,
    SafetyCertificateOutlined,
    TeamOutlined,
} from "@ant-design/icons";

export interface MenuItem {
    key: string;
    label: string;
    icon?: React.ReactNode;
    children?: MenuItem[];
}

export const menuItems: MenuItem[] = [
    {
        key: "/",
        label: "Dashboard",
        icon: <DashboardOutlined />,
    },
    {
        key: "/users",
        label: "Users",
        icon: <TeamOutlined />,
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
    {
        key: "/totp",
        label: "TOTP",
        icon: <SafetyCertificateOutlined />,
    },
];
