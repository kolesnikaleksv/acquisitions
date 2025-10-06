import logger from '#config/logger.js';
import { formatValidationError } from '#utils/format.js';
import { signupSchema } from '#validations/auth.validations.js';
import { createUser } from '../services/auth.service.js';
import { jwttoken } from '#utils/jwt.js';
import { cookies } from '#utils/cookies.js';

export const signup = async (req, res, next) => {
  try {
    const ValidationResult = signupSchema.safeParse(req.body);

    if (!ValidationResult.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationError(ValidationResult.error),
      });
    }

    const { name, role, email, password } = ValidationResult.data;

    const user = await createUser({ name, password, email, role });

    const token = jwttoken.sign({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    });

    cookies.set(res, 'token', token);

    logger.info(`User registred saccessfully: ${email}`);

    res.status(201).json({
      message: 'User registred',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    logger.error('Signup error', error);

    if (error.message === 'User with this email already exists') {
      return res.status(409).json({ error: 'User already exists' });
    }

    next(error);
  }
};
