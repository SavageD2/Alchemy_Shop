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

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
    if (user && await bcrypt.compare(password, user.password)) {
      return user;
    }
    return null;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async login(user: AuthenticatedUser) {
    const payload = { email: user.email, sub: user.id, role: user.role };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
