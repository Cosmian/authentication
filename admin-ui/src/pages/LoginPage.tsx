import { Alert, Button, Card, Form, Input, Typography } from "antd";
import { LockOutlined, SafetyCertificateOutlined, UserOutlined } from "@ant-design/icons";
import React, { useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import type { LoginResult } from "../contexts/AuthContext";
import { useBranding } from "../contexts/useBranding";

const { Title } = Typography;

const LoginPage: React.FC = () => {
    const { isAuthenticated, loading, login } = useAuth();
    const location = useLocation();
    const branding = useBranding();

    const [submitting, setSubmitting] = useState(false);
    const [totpStep, setTotpStep] = useState(false);
    const [credentials, setCredentials] = useState<{ username: string; password: string } | null>(null);
    const [error, setError] = useState<string | null>(null);

    const from = (location.state as { from?: { pathname: string } })?.from?.pathname ?? "/";

    if (!loading && isAuthenticated) {
        return <Navigate to={from} replace />;
    }

    const handleLogin = async (values: { username: string; password: string }): Promise<void> => {
        setSubmitting(true);
        setError(null);

        const result: LoginResult = await login(values.username, values.password);
        setSubmitting(false);

        switch (result.status) {
            case "authenticated":
                // AuthContext state update triggers re-render → Navigate above fires
                break;
            case "totp_required":
                setCredentials(values);
                setTotpStep(true);
                break;
            case "change_password":
                setError(result.message ?? "Your password has expired.");
                break;
            case "error":
                setError(result.message ?? "Authentication failed.");
                break;
        }
    };

    const handleTotp = async (values: { totp_code: string }): Promise<void> => {
        if (!credentials) return;
        setSubmitting(true);
        setError(null);

        const result: LoginResult = await login(credentials.username, credentials.password, values.totp_code);
        setSubmitting(false);

        switch (result.status) {
            case "authenticated":
                break;
            case "error":
                setError(result.message ?? "Invalid TOTP code.");
                break;
            default:
                setError("Unexpected response from server.");
                break;
        }
    };

    const outerStyle: React.CSSProperties = branding.backgroundImageUrl
        ? { backgroundImage: `url('${branding.backgroundImageUrl}')`, backgroundSize: "cover", backgroundPosition: "center" }
        : { background: "#f0f2f5" };
    const cardWrapperStyle: React.CSSProperties = branding.loginCardColor
        ? { backgroundColor: branding.loginCardColor, borderRadius: 8, padding: 8 }
        : {};

    return (
        <div className="flex items-center justify-center min-h-screen" style={outerStyle}>
            <div style={cardWrapperStyle}>
                <Card style={{ width: 400 }}>
                    <div className="text-center mb-6">
                        <Title level={3} className="m-0">
                            {branding.loginTitle}
                        </Title>
                        {branding.loginSubtitle && <p className="text-sm mt-1 mb-0">{branding.loginSubtitle}</p>}
                    </div>

                    {error && <Alert type="error" message={error} showIcon className="mb-4" closable onClose={() => setError(null)} />}

                    {!totpStep ? (
                        <Form onFinish={handleLogin} layout="vertical" autoComplete="off">
                            <Form.Item name="username" rules={[{ required: true, message: "Username is required" }]}>
                                <Input prefix={<UserOutlined />} placeholder="Username" size="large" autoFocus />
                            </Form.Item>
                            <Form.Item name="password" rules={[{ required: true, message: "Password is required" }]}>
                                <Input.Password prefix={<LockOutlined />} placeholder="Password" size="large" />
                            </Form.Item>
                            <Form.Item>
                                <Button type="primary" htmlType="submit" block size="large" loading={submitting}>
                                    Login
                                </Button>
                            </Form.Item>
                        </Form>
                    ) : (
                        <Form onFinish={handleTotp} layout="vertical" autoComplete="off">
                            <Alert
                                type="info"
                                message="Two-factor authentication required"
                                description="Enter the 6-digit code from your authenticator app."
                                showIcon
                                className="mb-4"
                            />
                            <Form.Item
                                name="totp_code"
                                rules={[
                                    { required: true, message: "TOTP code is required" },
                                    { len: 6, message: "Code must be 6 digits" },
                                    { pattern: /^\d{6}$/, message: "Code must be 6 digits" },
                                ]}
                            >
                                <Input prefix={<SafetyCertificateOutlined />} placeholder="000000" size="large" maxLength={6} autoFocus />
                            </Form.Item>
                            <Form.Item>
                                <Button type="primary" htmlType="submit" block size="large" loading={submitting}>
                                    Verify
                                </Button>
                            </Form.Item>
                            <Button
                                type="link"
                                block
                                onClick={() => {
                                    setTotpStep(false);
                                    setCredentials(null);
                                    setError(null);
                                }}
                            >
                                Back to login
                            </Button>
                        </Form>
                    )}
                </Card>
            </div>
        </div>
    );
};

export default LoginPage;
