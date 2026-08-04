import { Alert, Button, Descriptions, Input, message, Popconfirm, Space, Tag, Typography } from "antd";
import React, { useState } from "react";
import type { TokenInfo } from "../../types/api";
import { useAuth } from "../../contexts/AuthContext";
import { createTokenApi } from "../../services/tokenApi";

/** Formats a Unix timestamp (seconds) as a locale date-time, or a dash when zero. */
const formatEpoch = (secs: number): string => (secs > 0 ? new Date(secs * 1000).toLocaleString() : "—");

/** Token self-service inspector: paste a machine token to look it up, renew, or revoke it. */
export const TokenTab: React.FC = () => {
    const { serverUrl } = useAuth();
    const [token, setToken] = useState("");
    const [info, setInfo] = useState<TokenInfo | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    const runLookup = async () => {
        setError(null);
        setBusy(true);
        try {
            setInfo(await createTokenApi(serverUrl).lookup(token));
        } catch {
            setInfo(null);
            setError("Lookup failed — the token may be invalid, expired, or revoked");
        } finally {
            setBusy(false);
        }
    };

    const runRenew = async () => {
        setBusy(true);
        try {
            const res = await createTokenApi(serverUrl).renew(token);
            message.success(`Token renewed — new lease ${res.lease_duration}s`);
            await runLookup();
        } catch {
            message.error("Renew failed — the token may not be renewable");
        } finally {
            setBusy(false);
        }
    };

    const runRevoke = async () => {
        setBusy(true);
        try {
            await createTokenApi(serverUrl).revoke(token);
            message.success("Token revoked");
            setInfo(null);
            setToken("");
        } catch {
            message.error("Revoke failed");
        } finally {
            setBusy(false);
        }
    };

    return (
        <div style={{ maxWidth: 640 }}>
            <Typography.Paragraph type="secondary">
                Paste a machine token (obtained from AppRole or Kubernetes login) to inspect, renew, or revoke it. Tokens authenticate
                themselves — the admin session is not used here.
            </Typography.Paragraph>
            <Space.Compact className="w-full mb-3">
                <Input.Password
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    placeholder="Paste token…"
                    onPressEnter={() => token && runLookup()}
                />
                <Button type="primary" loading={busy} disabled={!token} onClick={runLookup}>
                    Lookup
                </Button>
            </Space.Compact>

            {error && <Alert type="error" showIcon message={error} className="mb-3" />}

            {info && (
                <>
                    <Descriptions bordered column={1} size="small">
                        <Descriptions.Item label="Token ID">
                            <Typography.Text code>{info.id}</Typography.Text>
                        </Descriptions.Item>
                        <Descriptions.Item label="Entity ID">{info.entity_id || "—"}</Descriptions.Item>
                        <Descriptions.Item label="Policies">
                            {info.policies.length > 0 ? info.policies.map((p) => <Tag key={p}>{p}</Tag>) : "—"}
                        </Descriptions.Item>
                        <Descriptions.Item label="Renewable">{info.renewable ? "Yes" : "No"}</Descriptions.Item>
                        <Descriptions.Item label="TTL remaining">{info.ttl}s</Descriptions.Item>
                        <Descriptions.Item label="Created">{formatEpoch(info.creation_time)}</Descriptions.Item>
                    </Descriptions>
                    <Space className="mt-3">
                        <Button loading={busy} disabled={!info.renewable} onClick={runRenew}>
                            Renew
                        </Button>
                        <Popconfirm title="Revoke this token? This cannot be undone." onConfirm={runRevoke} okText="Revoke" okType="danger">
                            <Button danger loading={busy}>
                                Revoke
                            </Button>
                        </Popconfirm>
                    </Space>
                </>
            )}
        </div>
    );
};
