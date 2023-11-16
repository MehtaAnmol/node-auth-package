import { Document } from "mongoose";

export interface UserDocument extends Document {
  username: string;
  password: string;
  comparePassword(candidatePassword: string): Promise<boolean>;
}