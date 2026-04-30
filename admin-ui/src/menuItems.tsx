import {
    ClockCircleOutlined,
    CrownOutlined,
    DashboardOutlined,
    KeyOutlined,
    SafetyCertificateOutlined,
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
        key: "/admins",
        label: "Admins",
        icon: <CrownOutlined />,
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
