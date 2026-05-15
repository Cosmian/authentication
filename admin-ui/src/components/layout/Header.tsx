import { LogoutOutlined, MoonOutlined, SunOutlined, UserOutlined } from "@ant-design/icons";
import { Button, Select, Switch, Typography } from "antd";
import React from "react";
import { useAuth } from "../../contexts/AuthContext";
import { useRealm } from "../../contexts/RealmContext";
import { SUPER_ADMIN_REALM_ID, SUPER_ADMIN_REALM_LABEL } from "../../constants/apiPaths";

const { Text } = Typography;

interface HeaderProps {
    isDarkMode: boolean;
    setIsDarkMode: (value: boolean) => void;
}

export const Header: React.FC<HeaderProps> = ({ isDarkMode, setIsDarkMode }) => {
    const { username, logout } = useAuth();
    const { realms, selectedRealm, setSelectedRealm, loading } = useRealm();

    return (
        <div className="flex items-center justify-between w-full h-full px-4">
            <div className="flex items-center gap-4">
                <h1 className="text-xl font-bold m-0 whitespace-nowrap">Auth Admin</h1>
                <Select
                    value={selectedRealm}
                    onChange={setSelectedRealm}
                    loading={loading}
                    style={{ minWidth: 160 }}
                    options={realms.map((r) => ({
                        value: r.id,
                        label: r.id === SUPER_ADMIN_REALM_ID ? SUPER_ADMIN_REALM_LABEL : r.id,
                    }))}
                />
            </div>
            <div className="flex items-center gap-4">
                <Switch
                    className="w-20"
                    checked={isDarkMode}
                    onChange={() => setIsDarkMode(!isDarkMode)}
                    checkedChildren={<MoonOutlined />}
                    unCheckedChildren={<SunOutlined />}
                />
                {username && (
                    <Text type="secondary">
                        <UserOutlined /> {username}
                    </Text>
                )}
                <Button icon={<LogoutOutlined />} onClick={logout} size="small">
                    Logout
                </Button>
            </div>
        </div>
    );
};
