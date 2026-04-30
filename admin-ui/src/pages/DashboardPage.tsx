import { Alert, Card, Col, Row, Typography } from "antd";
import { AppstoreOutlined, ClockCircleOutlined, CrownOutlined, KeyOutlined, SafetyCertificateOutlined } from "@ant-design/icons";
import { Link } from "react-router-dom";
import { useRealm } from "../contexts/RealmContext";

const { Title, Text } = Typography;

interface Section {
    title: string;
    path: string;
    icon: React.ReactNode;
    description: string;
    superAdminOnly?: boolean;
}

const sections: Section[] = [
    { title: "Realms", path: "/realms", icon: <AppstoreOutlined style={{ fontSize: 24 }} />, description: "Manage authentication realms", superAdminOnly: true },
    { title: "Admins", path: "/admins", icon: <CrownOutlined style={{ fontSize: 24 }} />, description: "Manage administrator accounts" },
    {
        title: "Credentials",
        path: "/credentials",
        icon: <KeyOutlined style={{ fontSize: 24 }} />,
        description: "Manage username/password credentials",
    },
    {
        title: "Sessions",
        path: "/sessions",
        icon: <ClockCircleOutlined style={{ fontSize: 24 }} />,
        description: "View and revoke active sessions",
    },
    {
        title: "TOTP",
        path: "/totp",
        icon: <SafetyCertificateOutlined style={{ fontSize: 24 }} />,
        description: "Manage two-factor authentication",
    },
];

const DashboardPage: React.FC = () => {
    const { selectedRealm, realmLabel, isSuperAdmin, error } = useRealm();

    const visibleSections = sections.filter((s) => !s.superAdminOnly || isSuperAdmin);

    return (
        <div>
            <Title level={2}>Dashboard</Title>
            <Text type="secondary">
                Managing realm: <Text strong>{realmLabel(selectedRealm)}</Text>
            </Text>

            {error && <Alert type="warning" message={error} showIcon className="mt-4 mb-4" />}

            <Row gutter={[16, 16]} className="mt-6">
                {visibleSections.map((section) => (
                    <Col xs={24} sm={12} lg={6} key={section.path}>
                        <Link to={section.path}>
                            <Card hoverable className="h-full">
                                <div className="flex flex-col items-center gap-2 text-center">
                                    {section.icon}
                                    <Title level={4} className="m-0">
                                        {section.title}
                                    </Title>
                                    <Text type="secondary">{section.description}</Text>
                                </div>
                            </Card>
                        </Link>
                    </Col>
                ))}
            </Row>
        </div>
    );
};

export default DashboardPage;
