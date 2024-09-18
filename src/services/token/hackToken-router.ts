import { Request, Response, Router } from "express";
import { StatusCode } from "status-code-enum";
import Config from "../../config.js";
import * as crypto from 'crypto';

const hackTokenRouter: Router = Router();

/**
 * @api {METHOD} SERVICE/ENDPOINT SERVICE/ENDPOINT
 * @apiGroup SERVICE
 * @apiDescription SERVICE DESCRIPTION
 *
 * @apiParam {TYPE} PARAM1 DESC
 * @apiParam {TYPE} PARAM2 DESC
 * @apiParam {TYPE} PARAM3 DESC
 *
 * @apiSuccess (200: Success) {TYPE} NAME1 DESC
 * @apiSuccess (200: Success) {TYPE} NAME2 DESC
 * @apiSuccess (200: Success) {TYPE} NAME3 DESC

 * @apiSuccessExample Example Success Response:
 * 	HTTP/1.1 200 OK
 *	{
 *		"NAME1": VALUE1,
 * 		"NAME2": VALUE2,
 * 		"NAME3": VALUE3
 * 	}
 *
 * @apiUse strongVerifyErrors
 * @apiError (CODE: DESC) {TYPE} ERROR1 DESC
 * @apiError (CODE: DESC) {TYPE} ERROR2 DESC
 * @apiError (CODE: DESC) {TYPE} ERROR3 DESC
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
 * @api {METHOD} SERVICE/ENDPOINT SERVICE/ENDPOINT
 * @apiGroup SERVICE
 * @apiDescription SERVICE DESCRIPTION
 *
 * @apiParam {TYPE} PARAM1 DESC
 * @apiParam {TYPE} PARAM2 DESC
 * @apiParam {TYPE} PARAM3 DESC
 *
 * @apiSuccess (200: Success) {TYPE} NAME1 DESC
 * @apiSuccess (200: Success) {TYPE} NAME2 DESC
 * @apiSuccess (200: Success) {TYPE} NAME3 DESC

 * @apiSuccessExample Example Success Response:
 * 	HTTP/1.1 200 OK
 *	{
 *		"NAME1": VALUE1,
 * 		"NAME2": VALUE2,
 * 		"NAME3": VALUE3
 * 	}
 *
 * @apiUse strongVerifyErrors
 * @apiError (CODE: DESC) {TYPE} ERROR1 DESC
 * @apiError (CODE: DESC) {TYPE} ERROR2 DESC
 * @apiError (CODE: DESC) {TYPE} ERROR3 DESC
 */

// decoding
hackTokenRouter.post("/decode", (req: Request, res: Response) => {
    try {
        const { token, context } = req.body;
        if (!token || !context) {
            return res.status(StatusCode.ClientErrorBadRequest).json({ error: "Error1" });
        }

        const initial_v = Buffer.from(context, 'hex');
        const encrypted = Buffer.from(token, 'base64');

        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(Config.SECRET_EN_KEY), initial_v);
        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        const decryptedString = decrypted.toString('utf8');

        const [encoded, signature] = decryptedString.split('.');
        if (!encoded || !signature) {
            return res.status(StatusCode.ClientErrorBadRequest).json({ error: "Error2" });
        }

        const hmac = crypto.createHmac('sha256', Config.SECRET_KEY);
        hmac.update(Buffer.from(encoded, 'base64'));
        const received_signature = hmac.digest('base64');

        if (signature !== received_signature) {
            return res.status(StatusCode.ClientErrorUnauthorized).json({ error: "Error3" });
        }

        const decoded = Buffer.from(encoded, 'base64').toString('utf8');
        return res.status(StatusCode.SuccessOK).json(JSON.parse(decoded));
    } catch (error) {
        return res.status(StatusCode.ClientErrorBadRequest).json({ error: "Error4" });
    }
});

export default hackTokenRouter;