import { Alert, Button } from "antd";
import React from "react";
import { useNavigate } from "react-router-dom";
import { PageHeader } from "../components/common/PageHeader";

const TotpPage: React.FC = () => {
    const navigate = useNavigate();

    return (
        <div>
            <PageHeader title="TOTP" />
            <Alert
                type="info"
                showIcon
                message="TOTP is managed per admin"
                description="Two-factor authentication is configured on individual admin accounts. Use the Admins page to enable, verify, or disable TOTP for each administrator."
                className="mb-4"
            />
            <Button type="primary" onClick={() => navigate("/admins")}>
                Go to Admins
            </Button>
        </div>
    );
};

export default TotpPage;
