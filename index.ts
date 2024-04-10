import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import { createAccessToken } from "./jwt";

interface CustomRequest extends Request {
  user?: any;
}

export const verifyUser = (
  req: CustomRequest,
  res: Response,
  next: NextFunction
) => {
  const userAccessToken = req.cookies.accessToken;
  const userRefreshToken = req.cookies.refreshToken;

  if (!userRefreshToken) {
    return res
      .status(401)
      .json({ status: false, message: "invalid refresh token" });
  }

  jwt.verify(
    userAccessToken,
    process.env.ACCESS_SECRET_KEY || "",
    (err: jwt.VerifyErrors | null, decoded: any) => {
      if (err) {
        console.log("err.name", err.name);
        if (err.name === "JsonWebTokenError" && userRefreshToken) {
          jwt.verify(
            userRefreshToken,
            process.env.ACCESS_SECRET_KEY || "",
            (errRefresh: jwt.VerifyErrors | null, decodedRefresh: any) => {
              if (errRefresh) {
                return res
                  .status(401)
                  .json({ status: false, message: "invalid refresh token" });
              }
              const user = decodedRefresh.user;
              const newAccessToken = createAccessToken(
                user,
                process.env.ACCESS_SECRET_KEY || "",
                "15m"
              );
              res.cookie("user_accessToken", newAccessToken, {
                maxAge: 300000,
                httpOnly: true,
                secure: true,
                sameSite: "strict",
              });
              req.user = user;
              next();
            }
          );
        } else {
          return res.status(401).json({
            status: false,
            message: "Unauthorized - No token Provided",
          });
        }
      } else {
        const decodedUser = decoded.user as any;
        req.user = decodedUser;
        next();
      }
    }
  );
};
