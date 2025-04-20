import express from "express"
import cors from "cors"
import cookieParser from "cookie-parser"
import bodyParser from "body-parser"

const app = express()

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}))

app.use(express.json({ limit: '16kb' }));  // For parsing application/json
app.use(express.urlencoded({ extended: true, limit: '16kb' }));  // For parsing form data
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"))
app.use(cookieParser())

// routes import 
import userRouter from './routes/user.routes.js'


//routes declaration
app.use("/api/v1/users", userRouter)


// admin routes declaration




export { app }