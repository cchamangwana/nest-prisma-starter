import { PrismaService } from './../../prisma/prisma.service';
import { BadGatewayException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    const { email, password } = dto;
    const user = await this.prisma.user.findUnique({
      where: { email },
    });
    if (user) {
      throw new BadGatewayException('User already exists');
    }
    const hashedPassword = await this.hashPassword(password);

    await this.prisma.user.create({
      data: {
        email,
        hashedPassword,
      },
    });
    return { message: 'signup is sucessful' };
  }

  async signin() {
    return 'This is the signin route';
  }

  async signout() {
    return 'This is the signout route';
  }

  async hashPassword(password: string) {
    const salt = 10;

    const hashedPassword = await bcrypt.hash(password, salt);

    return hashedPassword;
  }
}
