import { Result } from "antd";

interface PlaceholderPageProps {
    title: string;
}

const PlaceholderPage: React.FC<PlaceholderPageProps> = ({ title }) => (
    <Result title={title || "Page"} subTitle="This feature is coming soon." status="info" />
);

export default PlaceholderPage;
