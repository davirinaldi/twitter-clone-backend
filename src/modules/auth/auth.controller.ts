import { Controller, Post, UseGuards, Body, Get, Req } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';       
import { LocalAuthGuard } from './guards/local-auth.guard';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { UserMeDto } from '../users/dto/user-me.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { CurrentUser } from './decorators/current-user.decorator';
import { User } from '../users/users.entity';
import { Request } from 'express';


  @ApiTags('auth')
  @Controller('auth')
  export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('login')
    @UseGuards(LocalAuthGuard)  // ← Usa sua validação!
    @ApiOperation({ summary: 'Login do usuário' })
    @ApiResponse({ status: 200, type: AuthResponseDto })
    async login(
      @CurrentUser() user: User, 
      @Body() loginDto: LoginDto,
      @Req() req: Request
    ): Promise<AuthResponseDto> {
      const context = {
        ip: req.ip || req.socket.remoteAddress,
        userAgent: req.get('User-Agent'),
        platform: 'web' // Pode ser detectado do User-Agent
      };
      
      return this.authService.login(user, context);
    }
    @Post('refresh')
    @UseGuards(JwtAuthGuard)  // Usuário precisa estar logado para renovar
    @ApiOperation({ summary: 'Renovar access token usando refresh token' })
    @ApiResponse({ status: 200, type: AuthResponseDto, description: 'Novos tokens gerados' })
    @ApiResponse({ status: 401, description: 'Refresh token inválido, expirado ou comprometido' })
    async refresh(
      @CurrentUser() user: User, 
      @Body() refreshDto: RefreshTokenDto,
      @Req() req: Request
    ): Promise<AuthResponseDto> {
      const context = {
        ip: req.ip || req.socket.remoteAddress,
        userAgent: req.get('User-Agent'),
      };
      
      return this.authService.refresh(user.id, refreshDto.refresh_token, context);
    }

    @Get('me')
    @UseGuards(JwtAuthGuard)  // ← Protege rota
    @ApiOperation({ summary: 'Perfil do usuário logado' })
    @ApiResponse({ status: 200, type: UserMeDto })
    async me(@CurrentUser() user: User): Promise<UserMeDto> {
      return this.authService.getMe(user.id)
    }

  }