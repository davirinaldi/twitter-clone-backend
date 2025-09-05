import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersModule } from '../users/users.module';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthService} from './auth.service';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { AuthController } from './auth.controller';

@Module({
    imports: [
      UsersModule,     // ← Já inclui UsersService
      PassportModule,  // ← Para strategies funcionarem
      JwtModule.registerAsync({
        useFactory: () => ({
          secret: process.env.JWT_SECRET,
          signOptions: {
            expiresIn: process.env.JWT_ACCESS_EXPIRATION
          },
        }),
      })
    ],
    providers: [
      AuthService,     // ← Seu service
      LocalStrategy,   // ← Strategy do login
      JwtStrategy,     // ← Strategy dos tokens
    ],
    controllers: [AuthController],
    exports: [AuthService], // ← Outros módulos podem usar
  })
export class AuthModule{}

