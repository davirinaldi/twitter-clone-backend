import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';       

  @Injectable()
  export class JwtStrategy extends PassportStrategy(Strategy)     
  {
    constructor(
      private usersService: UsersService,
      private configService: ConfigService,
    ) {
      super({
        jwtFromRequest:
    ExtractJwt.fromAuthHeaderAsBearerToken(),
        ignoreExpiration: false,
        secretOrKey: configService.get<string>('JWT_SECRET')!,     
      });
    }

    async validate(payload: any): Promise<any> {
      const user = await this.usersService.findOne(payload.sub);
      if (!user || !user.isActive) {
        throw new UnauthorizedException('Token inválido');        
      }

      const { password: _, ...result } = user;
      return result;
    }
  }