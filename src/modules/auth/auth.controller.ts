import { Controller, Post, UseGuards, Body, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';       
import { LocalAuthGuard } from './guards/local-auth.guard';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { UserMeDto } from '../users/dto/user-me.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { CurrentUser } from './decorators/current-user.decorator';
import { User } from '../users/users.entity';


  @ApiTags('auth')
  @Controller('auth')
  export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('login')
    @UseGuards(LocalAuthGuard)  // ← Usa sua validação!
    @ApiOperation({ summary: 'Login do usuário' })
    @ApiResponse({ status: 200, type: AuthResponseDto })
    async login(@CurrentUser() user: User, @Body() loginDto: LoginDto): Promise<AuthResponseDto> {
      // req.user já foi validado pelo LocalAuthGuard
      return this.authService.login(user);
    }
    @Get('me')
    @UseGuards(JwtAuthGuard)  // ← Que guard usar?
    @ApiOperation({ summary: 'Perfil do usuário logado' })
    @ApiResponse({ status: 200, type: UserMeDto })  // ← Que DTO na response?
    async me(@CurrentUser() user: User): Promise<UserMeDto> {
      return this.authService.getMe(user.id)
    }

  }