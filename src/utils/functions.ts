import bcrypt from 'bcrypt';

/**
 * @param password: simple password text which needs to be converted into hashed
 * @returns Promise of hashed Password
 */
export const getHashedPassword = async (password: string): Promise<string> => {
  const hashedPwd = await bcrypt.hash(password, 10);
  return hashedPwd;
}

/**
 * @param password: simple text which user enters
 * @param hash: hash stored in database
 * @returns Promise of boolean if the entered password and the compares or not
 */
export const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return await bcrypt.compare(password, hash);
}