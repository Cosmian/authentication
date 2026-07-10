import { Alert, Badge, Card, Col, Row, Steps, Tag, Typography } from "antd";
import { ArrowRightOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { API_VERSION, SUPER_ADMIN_REALM_ID } from "../constants/apiPaths";
import { useAuth } from "../contexts/AuthContext";
import { useRealm } from "../contexts/RealmContext";
import { apiGet } from "../services/api";
import type { Realm, VersionResponse } from "../types/api";
import { formatDuration } from "../utils/formatDuration";

const { Title, Text } = Typography;

function getAuthMethods(realm: Realm): string[] {
    const methods: string[] = [];
    if (realm.auth_params.username_password_params) methods.push("Password");
    if (realm.auth_params.jwt_params) methods.push("JWT");
    if (realm.auth_params.totp_params) methods.push("TOTP");
    return methods;
}

const DashboardPage: React.FC = () => {
    const { serverUrl } = useAuth();
    const { realms, error } = useRealm();
    const navigate = useNavigate();

    const [serverVersion, setServerVersion] = useState<string | null>(null);
    const [serverOnline, setServerOnline] = useState(true);

    const concreteRealms = realms.filter((r) => r.id !== SUPER_ADMIN_REALM_ID);
    const isOnboarding = concreteRealms.length === 0;

    const displayedRealms = realms;

    const fetchVersion = useCallback(async () => {
        try {
            const { version } = await apiGet<VersionResponse>(serverUrl, API_VERSION);
            setServerVersion(version);
            setServerOnline(true);
        } catch {
            setServerVersion(null);
            setServerOnline(false);
        }
    }, [serverUrl]);

    useEffect(() => {
        fetchVersion();
    }, [fetchVersion]);

    if (error) {
        return <Alert type="warning" message={error} showIcon className="mt-4" />;
    }

    if (isOnboarding) {
        return (
            <div>
                <Title level={2}>Welcome</Title>
                <Text type="secondary">Get started by setting up your first authentication realm.</Text>
                <Card className="mt-6" style={{ maxWidth: 600 }}>
                    <Steps
                        direction="vertical"
                        current={-1}
                        items={[
                            {
                                title: "Create a realm",
                                description: (
                                    <span>
                                        Define an authentication domain. <Link to="/realms">Go &rarr;</Link>
                                    </span>
                                ),
                            },
                            {
                                title: "Add credentials",
                                description: (
                                    <span>
                                        Create username/password entries for your realm. <Link to="/credentials">Go &rarr;</Link>
                                    </span>
                                ),
                            },
                            {
                                title: "Enable TOTP (optional)",
                                description: (
                                    <span>
                                        Set up two-factor authentication. <Link to="/admins">Go &rarr;</Link>
                                    </span>
                                ),
                            },
                        ]}
                    />
                </Card>
            </div>
        );
    }

    return (
        <div>
            <Title level={2}>Dashboard</Title>

            {/* Server status bar */}
            <Card size="small" className="mb-4">
                <div className="flex items-center gap-6 flex-wrap">
                    <span>
                        <Text type="secondary">Status: </Text>
                        {serverOnline ? <Badge status="success" text="Online" /> : <Badge status="error" text="Unreachable" />}
                    </span>
                    <span>
                        <Text type="secondary">Version: </Text>
                        <Text strong>{serverVersion ?? "—"}</Text>
                    </span>
                    <span>
                        <Text type="secondary">Realms: </Text>
                        <Text strong>{displayedRealms.length}</Text>
                    </span>
                </div>
            </Card>

            {/* Realm overview cards */}
            <Title level={4} className="mt-6 mb-4">
                Realms
            </Title>
            <Row gutter={[16, 16]}>
                {displayedRealms.map((realm) => {
                    const methods = getAuthMethods(realm);
                    return (
                        <Col xs={24} sm={12} lg={8} key={realm.id}>
                            <Card
                                title={realm.id === SUPER_ADMIN_REALM_ID ? "_ (Super-Admin)" : realm.id}
                                hoverable
                                style={{ minHeight: 140 }}
                                onClick={() => {
                                    navigate("/realms");
                                }}
                            >
                                <div className="flex flex-col gap-2">
                                    <div>
                                        <Text type="secondary">Session: </Text>
                                        <Text>{formatDuration(realm.session_max_age_seconds)}</Text>
                                        <Text type="secondary"> / Stale: </Text>
                                        <Text>{formatDuration(realm.session_max_stale_age_seconds)}</Text>
                                    </div>
                                    <div>
                                        {methods.map((m) => (
                                            <Tag key={m}>{m}</Tag>
                                        ))}
                                    </div>
                                    <div className="flex gap-2 mt-2">
                                        <Typography.Link
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                navigate("/credentials");
                                            }}
                                        >
                                            Credentials <ArrowRightOutlined />
                                        </Typography.Link>
                                        <Typography.Link
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                navigate("/sessions");
                                            }}
                                        >
                                            Sessions <ArrowRightOutlined />
                                        </Typography.Link>
                                    </div>
                                </div>
                            </Card>
                        </Col>
                    );
                })}
            </Row>
        </div>
    );
};

export default DashboardPage;
