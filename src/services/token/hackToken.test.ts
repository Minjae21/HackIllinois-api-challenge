// import { describe, expect, it } from "@jest/globals";
// import express from "express";
// import request from "supertest";
// import { StatusCode } from "status-code-enum";
// import hackTokenRouter from "./hackToken-router";

// const app = express();
// app.use(express.json());
// app.use('/token', hackTokenRouter);

// describe("POST /token/encode, POST /token/decode", () => {
//     it("TEST1: should successfully encode user data into a JWT token", async () => {
//         const userInfo = { username: "Jane Dog" };

//         const encodeResponse = await request(app)
//             .post("/token/encode/")
//             .send(userInfo)
//             .expect(StatusCode.SuccessOK);

//             const encrypted = encodeResponse.body;
//         const token = encrypted.token;

//         const decodeResponse = await request(app)
//             .post("/token/decode/")
//             .send({ token, context: encodeResponse.body.context })
//             .expect(StatusCode.SuccessOK);

//         expect(JSON.parse(decodeResponse.text)).toHaveProperty("username", userInfo.username);
//     });
// });
