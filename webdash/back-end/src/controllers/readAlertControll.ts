import { Request, Response } from "express";
import readAlertSer from "../services/readAlertService";
export default async function readAlertControll(req:Request, res:Response){
    try{
        const date = req.query.date;
        const arr = await readAlertSer(date as string);
        res.json(arr);
    }catch {
        res.json([]);
    }
}