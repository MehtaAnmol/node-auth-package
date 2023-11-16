import jwt from 'jsonwebtoken';
import { Login, Response as ApiResponse } from '../types';
import { comparePassword } from '../utils/functions';
import config from '../config/config';

export const login = async (user: Login) => {
  const res: ApiResponse = {
    data: '',
    status: 200,
  }

  try {

    const passwordMatch: boolean = await comparePassword(user.password, user.hash);

    if (!passwordMatch) {
      res.status = 401;
      res.data = { message: 'Invalid credentials' };
    }

    const token: string = jwt.sign({ userId: user.id, username: user.username }, config.secretKey, {
      expiresIn: config.tokenLife,
    });

    const refreshToken: string = jwt.sign({ userId: user.id, username: user.username }, config.refreshTokenSecret, {
      expiresIn: config.refreshTokenLife,
    });

    res.status = 200;
    res.data = {
      token,
      refreshToken
    };
  } catch (error) {
    res.status = 500;
    res.data = { error: 'Internal Server Error' };
  }
  return res;
};

export const token = (refreshToken: string) => {
  const res: ApiResponse = {
    data: '',
    status: 200,
  }

  if (!refreshToken) {
    res.status = 401;
    res.data = { message: 'Unauthorized: Refresh token not provided' };
  }

  jwt.verify(refreshToken, config.refreshTokenSecret, (err: any, user: any) => {
    if (err) {
      res.status = 403;
      res.data = { message: 'Forbidden: Invalid refresh token' };
    }

    const token: string = jwt.sign({ userId: user.userId, username: user.username }, config.secretKey, {
      expiresIn: config.tokenLife,
    });

    res.status = 200;
    res.data = { token };
    return res;
  });
};
