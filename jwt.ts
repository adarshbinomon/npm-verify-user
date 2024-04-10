import jwt from "jsonwebtoken";
import { Response } from "express";

export const createAccessToken = (
  user: any,
  accessTokenSecretKey: string,
  expiration: string
) => {
  const token = jwt.sign({ user }, accessTokenSecretKey, {
    expiresIn: expiration,
  });
  return token;
};

export const createRefreshToken = (
  user: any,
  refreshTokenSecretKey: string,
  expiration: string
) => {
  return jwt.sign({ user }, refreshTokenSecretKey, { expiresIn: expiration });
};

export const clearAccessTokenFromCookie = (
  cookieName: string,
  res: Response
) => {
  console.log("attachAccesTokenToCookie - not http only ", "development");
  res.cookie(cookieName, {
    httpOnly: false,
    secure: false,
    signed: false,
    maxAge: 0,
  });
};
