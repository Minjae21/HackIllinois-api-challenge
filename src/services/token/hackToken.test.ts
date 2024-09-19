import request from "supertest";
import express from "express";
import hackTokenRouter from "./hackToken-router";
import { describe, expect, it } from "@jest/globals";
import StatusCode from "status-code-enum";

const hackTokenApp = express();
hackTokenApp.use(express.json());
hackTokenApp.use("/token", hackTokenRouter);

// Error test cases
describe("POST /token/decode", () => {
    it("Missing parameters", async () => {
        const response = await request(hackTokenApp).post("/token/decode").send({}).expect(StatusCode.ClientErrorBadRequest);

        expect(response.body).toEqual({ error: "Missing Parameters" });
    });

    it("Invalid parameters", async () => {
        const response = await request(hackTokenApp)
            .post("/token/decode")
            .send({ token: "Invalid", context: "Invalid" })
            .expect(StatusCode.ClientErrorBadRequest);

        expect(response.body).toEqual({ error: "Invalid Parameters" });
    });

    it("Unauthorized token", async () => {
        const response = await request(hackTokenApp)
            .post("/token/decode")
            .send({ token: "random", context: "random" })
            .expect(StatusCode.ClientErrorBadRequest);

        expect(response.body).toEqual({ error: "Invalid Parameters" });
    });
});
