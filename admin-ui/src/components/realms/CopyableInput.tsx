import { CopyOutlined } from "@ant-design/icons";
import { Button, Input, message, Space } from "antd";
import React from "react";

export interface CopyableInputProps {
    /** Set by Form.Item so its label points at the input. */
    id?: string;
    value?: string;
    onChange?: (event: React.ChangeEvent<HTMLInputElement>) => void;
    placeholder?: string;
    /** Accessible name of the copy button. */
    copyLabel: string;
}

/** A text input with a button copying its value, for values the admin pastes into the IdP. */
export const CopyableInput: React.FC<CopyableInputProps> = ({ id, value, onChange, placeholder, copyLabel }) => {
    const copy = async (): Promise<void> => {
        try {
            await navigator.clipboard.writeText(value ?? "");
            message.success("Copied to clipboard");
        } catch {
            message.error("Could not copy to the clipboard");
        }
    };
    return (
        <Space.Compact className="w-full">
            <Input id={id} value={value} onChange={onChange} placeholder={placeholder} />
            <Button icon={<CopyOutlined />} aria-label={copyLabel} onClick={copy} disabled={!value} />
        </Space.Compact>
    );
};
