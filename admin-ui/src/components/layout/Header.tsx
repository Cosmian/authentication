import { MoonOutlined, SunOutlined } from "@ant-design/icons";
import { Select, Switch } from "antd";
import React from "react";
import { useRealm } from "../../contexts/RealmContext";

interface HeaderProps {
    isDarkMode: boolean;
    setIsDarkMode: (value: boolean) => void;
}

export const Header: React.FC<HeaderProps> = ({ isDarkMode, setIsDarkMode }) => {
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
                    options={realms.map((r) => ({ value: r.id, label: r.label }))}
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
            </div>
        </div>
    );
};
