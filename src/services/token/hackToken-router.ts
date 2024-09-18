import { Request, Response, Router } from "express";
import { StatusCode } from "status-code-enum";
import Config from "../../config.js";
import * as crypto from 'crypto';

const hackTokenRouter: Router = Router();

/**
 * @api {post} /token/encode/ POST /token/encode/
 * @apiGroup token
 * @apiDescription Encode your data, get a encrypted token that can be decrpted
 *
 * @apiSuccess (200: Success) {String} T encrypted token
 * @apiSuccessExample Example Success Response:
 * 	HTTP/1.1 200 OK
* {
*    "token": "7eLFraeBhbdpk4pxJWGwfRSQn4fNtYo4jW5wwiJDCF0IKADjcsbacUP/ygdBioCvPDZERGinwP/kI9TNI8L8YXPlX2SGf4Q2F51scarZBTLiCZO3aQB+SMCPIZKfub1A",
*    "context": "8528e91688c79cdb20c9004ca4537b04"
* }
 *
 */

// encoding
hackTokenRouter.post("/encode", (req: Request, res: Response) => {
    const json = JSON.stringify(req.body);
    const b64Data = Buffer.from(json).toString('base64');

    const hmac = crypto.createHmac('sha256', Config.SECRET_KEY);
    hmac.update(Buffer.from(b64Data, 'base64'));
    const signature = hmac.digest('base64');
    const token = `${b64Data}.${signature}`;

    // eslint-disable-next-line no-magic-numbers
    const initial_v = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(Config.SECRET_EN_KEY), initial_v);
    let encrypted = cipher.update(token);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    res.status(StatusCode.SuccessOK).json({
        token: encrypted,
        context: initial_v.toString('hex')
    });
});

/**
 * @api {post} /token/decode/ POST /token/decode/
 * @apiGroup token
 * @apiDescription Decode your data from encrypted token
 *
 * @apiSuccessExample Example Success Response:
 * 	HTTP/1.1 200 OK
 * {
 *    "name": "Jane Doe",
 *    "age": "21"
 * }
 *
 * @apiError (400: Bad Request) {String} Missing parameters
 * @apiError (400: Bad Request) {String} Invalid  parameters
 * @apiError (401: Unauthorized) {String} Unauthorized token
 */

// decoding
hackTokenRouter.post("/decode", (req: Request, res: Response) => {
    try {
        const { token, context } = req.body;
        if (!token || !context) {
            return res.status(StatusCode.ClientErrorBadRequest).json({ error: "Missing Parameters" });
        }

        const initial_v = Buffer.from(context, 'hex');
        const encrypted = Buffer.from(token, 'base64');

        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(Config.SECRET_EN_KEY), initial_v);
        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        const decryptedString = decrypted.toString('utf8');

        const [encoded, signature] = decryptedString.split('.');
        if (!encoded || !signature) {
            return res.status(StatusCode.ClientErrorBadRequest).json({ error: "Invalid Parameters" });
        }

        const hmac = crypto.createHmac('sha256', Config.SECRET_KEY);
        hmac.update(Buffer.from(encoded, 'base64'));
        const received_signature = hmac.digest('base64');

        if (signature !== received_signature) {
            return res.status(StatusCode.ClientErrorUnauthorized).json({ error: "Unauthorized Token" });
        }

        const decoded = Buffer.from(encoded, 'base64').toString('utf8');
        return res.status(StatusCode.SuccessOK).json(JSON.parse(decoded));
    } catch (error) {
        return res.status(StatusCode.ClientErrorBadRequest).json({ error: "Invalid Parameters" });
    }
});

export default hackTokenRouter;