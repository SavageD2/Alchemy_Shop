import { UserRole } from 'src/users/entities/user.entity';

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: UserRole;
  shopId?: string;
}

export interface JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
    shopId?: string;
}