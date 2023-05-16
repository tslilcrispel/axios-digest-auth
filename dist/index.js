"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const url = require("url");
const axios = require("axios");
class AxiosDigestAuth {
    constructor({ axios: axiosInst, password, username }) {
        this.axios = axiosInst ? axiosInst : axios.default;
        this.count = 0;
        this.password = password;
        this.username = username;
    }
    getNewRequestOpts(opts, resp) {
        var _a, _b;
        if (resp.response === undefined
            || resp.response.status !== 401
            || !((_a = resp.response.headers["www-authenticate"]) === null || _a === void 0 ? void 0 : _a.includes('nonce'))) {
            throw resp;
        }
        const authDetails = resp.response.headers['www-authenticate'].split(',').map((v) => v.split('='));
        ++this.count;
        const nonceCount = ('00000000' + this.count).slice(-8);
        const cnonce = crypto.randomBytes(24).toString('hex');
        const realm = authDetails.find((el) => el[0].toLowerCase().indexOf("realm") > -1)[1].replace(/"/g, '');
        const nonce = authDetails.find((el) => el[0].toLowerCase().indexOf("nonce") > -1)[1].replace(/"/g, '');
        const ha1 = crypto.createHash('md5').update(`${this.username}:${realm}:${this.password}`).digest('hex');
        const path = url.parse(opts.url).pathname;
        const ha2 = crypto.createHash('md5').update(`${(_b = opts.method) !== null && _b !== void 0 ? _b : "GET"}:${path}`).digest('hex');
        const response = crypto.createHash('md5').update(`${ha1}:${nonce}:${nonceCount}:${cnonce}:auth:${ha2}`).digest('hex');
        const authorization = `Digest username="${this.username}",realm="${realm}",` +
            `nonce="${nonce}",uri="${path}",qop="auth",algorithm="MD5",` +
            `response="${response}",nc="${nonceCount}",cnonce="${cnonce}"`;
        if (opts.headers) {
            opts.headers["authorization"] = authorization;
        }
        else {
            opts.headers = { authorization };
        }
        return opts;
    }
    async request(opts) {
        try {
            return await this.axios.request(opts);
        }
        catch (resp1) {
            const newOptions = this.getNewRequestOpts(opts, resp1);
            try {
                return this.axios.request(newOptions);
            }
            catch (resp2) {
                const reChallengeOpts = this.getNewRequestOpts(newOptions, resp2);
                return this.axios.request(reChallengeOpts);
            }
        }
    }
}
exports.default = AxiosDigestAuth;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSxpQ0FBaUM7QUFDakMsMkJBQTJCO0FBQzNCLCtCQUErQjtBQWlCL0IsTUFBcUIsZUFBZTtJQU9sQyxZQUFZLEVBQUUsS0FBSyxFQUFFLFNBQVMsRUFBRSxRQUFRLEVBQUUsUUFBUSxFQUF1QjtRQUN2RSxJQUFJLENBQUMsS0FBSyxHQUFHLFNBQVMsQ0FBQyxDQUFDLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDO1FBQ25ELElBQUksQ0FBQyxLQUFLLEdBQUcsQ0FBQyxDQUFDO1FBQ2YsSUFBSSxDQUFDLFFBQVEsR0FBRyxRQUFRLENBQUM7UUFDekIsSUFBSSxDQUFDLFFBQVEsR0FBRyxRQUFRLENBQUM7SUFDM0IsQ0FBQztJQUVPLGlCQUFpQixDQUFDLElBQThCLEVBQUUsSUFBUzs7UUFDL0QsSUFBSSxJQUFJLENBQUMsUUFBUSxLQUFLLFNBQVM7ZUFDeEIsSUFBSSxDQUFDLFFBQVEsQ0FBQyxNQUFNLEtBQUssR0FBRztlQUM1QixDQUFDLENBQUEsTUFBQSxJQUFJLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxrQkFBa0IsQ0FBQywwQ0FBRSxRQUFRLENBQUMsT0FBTyxDQUFDLENBQUEsRUFDbEU7WUFDRSxNQUFNLElBQUksQ0FBQztTQUNkO1FBQ0QsTUFBTSxXQUFXLEdBQUcsSUFBSSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsa0JBQWtCLENBQUMsQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBUyxFQUFFLEVBQUUsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7UUFDMUcsRUFBRSxJQUFJLENBQUMsS0FBSyxDQUFDO1FBQ2IsTUFBTSxVQUFVLEdBQUcsQ0FBQyxVQUFVLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBQ3ZELE1BQU0sTUFBTSxHQUFHLE1BQU0sQ0FBQyxXQUFXLENBQUMsRUFBRSxDQUFDLENBQUMsUUFBUSxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ3RELE1BQU0sS0FBSyxHQUFHLFdBQVcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxFQUFPLEVBQUUsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsSUFBSSxFQUFFLEVBQUUsQ0FBQyxDQUFDO1FBQzVHLE1BQU0sS0FBSyxHQUFHLFdBQVcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxFQUFPLEVBQUUsRUFBRSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsSUFBSSxFQUFFLEVBQUUsQ0FBQyxDQUFDO1FBQzVHLE1BQU0sR0FBRyxHQUFHLE1BQU0sQ0FBQyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUMsTUFBTSxDQUFDLEdBQUcsSUFBSSxDQUFDLFFBQVEsSUFBSSxLQUFLLElBQUksSUFBSSxDQUFDLFFBQVEsRUFBRSxDQUFDLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ3hHLE1BQU0sSUFBSSxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLEdBQUksQ0FBQyxDQUFDLFFBQVEsQ0FBQztRQUMzQyxNQUFNLEdBQUcsR0FBRyxNQUFNLENBQUMsVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDLE1BQU0sQ0FBQyxHQUFHLE1BQUEsSUFBSSxDQUFDLE1BQU0sbUNBQUksS0FBSyxJQUFJLElBQUksRUFBRSxDQUFDLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQzdGLE1BQU0sUUFBUSxHQUFHLE1BQU0sQ0FBQyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUMsTUFBTSxDQUFDLEdBQUcsR0FBRyxJQUFJLEtBQUssSUFBSSxVQUFVLElBQUksTUFBTSxTQUFTLEdBQUcsRUFBRSxDQUFDLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ3RILE1BQU0sYUFBYSxHQUFHLG9CQUFvQixJQUFJLENBQUMsUUFBUSxZQUFZLEtBQUssSUFBSTtZQUN4RSxVQUFVLEtBQUssVUFBVSxJQUFJLCtCQUErQjtZQUM1RCxhQUFhLFFBQVEsU0FBUyxVQUFVLGFBQWEsTUFBTSxHQUFHLENBQUM7UUFDbkUsSUFBSSxJQUFJLENBQUMsT0FBTyxFQUFFO1lBQ2QsSUFBSSxDQUFDLE9BQU8sQ0FBQyxlQUFlLENBQUMsR0FBRyxhQUFhLENBQUM7U0FDakQ7YUFBTTtZQUNILElBQUksQ0FBQyxPQUFPLEdBQUcsRUFBRSxhQUFhLEVBQUUsQ0FBQztTQUNwQztRQUNELE9BQU8sSUFBSSxDQUFBO0lBQ2YsQ0FBQztJQUVNLEtBQUssQ0FBQyxPQUFPLENBQUMsSUFBOEI7UUFDakQsSUFBSTtZQUNGLE9BQU8sTUFBTSxJQUFJLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQztTQUN2QztRQUFDLE9BQU8sS0FBVSxFQUFFO1lBQ2pCLE1BQU0sVUFBVSxHQUFHLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxJQUFJLEVBQUUsS0FBSyxDQUFDLENBQUE7WUFDdEQsSUFBSTtnQkFDQSxPQUFPLElBQUksQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDLFVBQVUsQ0FBQyxDQUFDO2FBQ3pDO1lBQ0QsT0FBTyxLQUFVLEVBQUU7Z0JBQ2YsTUFBTSxlQUFlLEdBQUcsSUFBSSxDQUFDLGlCQUFpQixDQUFDLFVBQVUsRUFBRSxLQUFLLENBQUMsQ0FBQTtnQkFDakUsT0FBTyxJQUFJLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxlQUFlLENBQUMsQ0FBQzthQUM5QztTQUNKO0lBQ0gsQ0FBQztDQUVGO0FBekRELGtDQXlEQyJ9