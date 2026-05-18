import { Button, Result } from "antd";
import { Link } from "react-router-dom";

const NotFoundPage: React.FC = () => (
    <Result
        status="404"
        title="404"
        subTitle="The page you are looking for does not exist."
        extra={
            <Link to="/">
                <Button type="primary">Back to Dashboard</Button>
            </Link>
        }
    />
);

export default NotFoundPage;
