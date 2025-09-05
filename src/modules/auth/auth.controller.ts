import { Controller, Post, UseGuards, Body } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';       
import { LocalAuthGuard } from './guards/local-auth.guard';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
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
  }