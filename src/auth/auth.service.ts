import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt/dist/jwt.service';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { AuthenticatedUser } from './interfaces/auth-user.interface';


@Injectable()
export class AuthService {
  
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService
  ) {}

  async validateUser(email: string, password: string): Promise<AuthenticatedUser | null> {
    const user = await this.usersService.findByEmail(email);
    if (user && (await bcrypt.compare(password, user.password))) {
      // Ne jamais retourner le password !
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, ...result } = user;
      return result as AuthenticatedUser;
    }
    return null;
  }

  async login(user: AuthenticatedUser) {
    const payload = {
      email: user.email,
      sub: user.id,
      role: user.role,
      shopId: user.shopId, // ⚠️ Important pour le multi-tenancy
    };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
