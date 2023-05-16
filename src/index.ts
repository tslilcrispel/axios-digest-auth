import * as crypto from "crypto";
import * as url from "url";
import * as axios from "axios";

/**
 * Options to configure the AxiosDigestAuth instance.
 */
export interface AxiosDigestAuthOpts {
  /**
   * optionally provide your own axios instance. if this is not provided, one will be created for
   * you with default settings.
   */
  axios?: axios.AxiosInstance;
  /** the http digest auth password */
  password: string;
  /** the http digest auth username */
  username: string;
}

export default class AxiosDigestAuth {

  private readonly axios: axios.AxiosInstance;
  private count: number;
  private readonly password: string;
  private readonly username: string;

  constructor({ axios: axiosInst, password, username }: AxiosDigestAuthOpts) {
    this.axios = axiosInst ? axiosInst : axios.default;
    this.count = 0;
    this.password = password;
    this.username = username;
  }

  private getNewRequestOpts(opts: axios.AxiosRequestConfig, resp: any) {
      if (resp.response === undefined
          || resp.response.status !== 401
          || !resp.response.headers["www-authenticate"]?.includes('nonce')
      ) {
          throw resp;
      }
      const authDetails = resp.response.headers['www-authenticate'].split(',').map((v: string) => v.split('='));
      ++this.count;
      const nonceCount = ('00000000' + this.count).slice(-8);
      const cnonce = crypto.randomBytes(24).toString('hex');
      const realm = authDetails.find((el: any) => el[0].toLowerCase().indexOf("realm") > -1)[1].replace(/"/g, '');
      const nonce = authDetails.find((el: any) => el[0].toLowerCase().indexOf("nonce") > -1)[1].replace(/"/g, '');
      const ha1 = crypto.createHash('md5').update(`${this.username}:${realm}:${this.password}`).digest('hex');
      const path = url.parse(opts.url!).pathname;
      const ha2 = crypto.createHash('md5').update(`${opts.method ?? "GET"}:${path}`).digest('hex');
      const response = crypto.createHash('md5').update(`${ha1}:${nonce}:${nonceCount}:${cnonce}:auth:${ha2}`).digest('hex');
      const authorization = `Digest username="${this.username}",realm="${realm}",` +
          `nonce="${nonce}",uri="${path}",qop="auth",algorithm="MD5",` +
          `response="${response}",nc="${nonceCount}",cnonce="${cnonce}"`;
      if (opts.headers) {
          opts.headers["authorization"] = authorization;
      } else {
          opts.headers = { authorization };
      }
      return opts
  }

  public async request(opts: axios.AxiosRequestConfig): Promise<axios.AxiosResponse> {
    try {
      return await this.axios.request(opts);
    } catch (resp1: any) {
        const newOptions = this.getNewRequestOpts(opts, resp1)
        try {
            return await this.axios.request(newOptions);
        }
        catch (resp2: any) {
            if (resp2.response && resp2.response.status === 401 && resp2.response.headers["www-authenticate"]?.includes('stale=true')) {
                const reChallengeOpts = this.getNewRequestOpts(newOptions, resp2)
                return this.axios.request(reChallengeOpts);
            }
            throw resp2;
        }
    }
  }

}
