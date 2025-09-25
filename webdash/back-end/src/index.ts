import express,{ Express } from "express";
import cors from "cors";
import readAlertRoute from "./routes/readAlertRoute";

const app:Express = express();
app.
    use(cors()).
    use(express.urlencoded()).
    use(express.json())

readAlertRoute(app);

app.listen(3000, () => {
    console.log("Server port 3000 is online.")
})