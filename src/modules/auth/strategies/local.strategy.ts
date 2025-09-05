import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../../users/users.service';
import * as bcrypt from 'bcrypt';

  @Injectable()
  export class LocalStrategy extends PassportStrategy(Strategy) {
    constructor(private usersService: UsersService) {
      super({
        usernameField: 'identifier',     
      });
    }

    async validate(identifier: string, password: string): Promise<any> {
      const user = await this.usersService.findByEmailOrUsername(identifier);       

      // Verificação única - não vaza informações específicas
      if (!user || !user.isActive || !await bcrypt.compare(password,
      user.password)) {
        throw new UnauthorizedException('Credenciais inválidas');
      }

      // Retorna usuário sem senha
      const { password: _, ...result } = user;
      return result;
    }
  }