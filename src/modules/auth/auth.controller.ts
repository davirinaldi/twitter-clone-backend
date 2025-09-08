import { Controller, Post, UseGuards, Body, Get, Req, Headers, Logger } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiSecurity } from '@nestjs/swagger';       
import { LocalAuthGuard } from './guards/local-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { LogoutDto } from './dto/logout.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { UserMeDto } from '../users/dto/user-me.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { LogoutResponseDto } from './dto/logout-response.dto';
import { CurrentUser } from './decorators/current-user.decorator';
import { Roles } from './decorators/roles.decorator';
import { Auth, AuthAdmin } from './decorators/auth.decorator';
import { Role } from './enums/role.enum';
import { User } from '../users/users.entity';
import { Request } from 'express';


  @ApiTags('auth')
  @Controller('auth')
  export class AuthController {
    private readonly logger = new Logger(AuthController.name);

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
    @Auth() // ← NEW: User authentication required (any role)
    @ApiOperation({ summary: 'Perfil do usuário logado' })
    @ApiResponse({ status: 200, type: UserMeDto })
    async me(@CurrentUser() user: User): Promise<UserMeDto> {
      return this.authService.getMe(user.id)
    }

    @Post('logout')
    @Auth() // ← NEW: Clean authentication decorator
    @ApiOperation({ 
      summary: 'Logout do usuário',
      description: 'Revoga tokens de refresh do usuário. Suporte a logout de device único ou todos os devices.'
    })
    @ApiResponse({ 
      status: 200, 
      type: LogoutResponseDto,
      description: 'Logout realizado com sucesso'
    })
    @ApiResponse({ 
      status: 401, 
      description: 'Token de acesso inválido ou expirado' 
    })
    async logout(
      @CurrentUser() user: User,
      @Body() logoutDto: LogoutDto,
      @Headers('authorization') authHeader: string,
      @Req() req: Request
    ): Promise<LogoutResponseDto> {
      // Framework Mental: Observability-first - structured logging
      const requestId = req.headers['x-request-id'] || 'unknown';
      const context = {
        userId: user.id, // Hash in real logging
        ip: req.ip || req.socket.remoteAddress,
        userAgent: req.get('User-Agent'),
        logoutAll: logoutDto.logoutAll,
        requestId
      };

      this.logger.log('Logout attempt', context);

      try {
        // Framework Mental: Security-first - extract token safely
        const token = authHeader?.replace('Bearer ', '') || '';
        
        // Framework Mental: Error handling - validate input
        if (!token) {
          this.logger.warn('Logout attempt without token', context);
          // Security: Always return success (don't leak info)
          return {
            message: 'Logged out successfully',
            loggedOutDevices: 0,
            timestamp: new Date().toISOString()
          };
        }

        // Framework Mental: Business logic delegation to service layer
        const result = await this.authService.logout(
          user.id,
          token,
          logoutDto.logoutAll || false
        );

        // Framework Mental: Observability - log success
        this.logger.log('Logout successful', {
          ...context,
          devicesLoggedOut: result.loggedOutDevices
        });

        return result;

      } catch (error: unknown) {
        let errorMessage: string;
        let errorStack: string | undefined;
      
        if (error instanceof Error) {
          errorMessage = error.message;
          errorStack = error.stack;
        } else if (typeof error === 'string') {
          errorMessage = error;
        } else {
          errorMessage = JSON.stringify(error);
        }
      
        this.logger.error('Logout error', {
          ...context,
          message: errorMessage,
          stack: errorStack,
        });

        // Framework Mental: Security-first - always return success response
        return {
          message: 'Logged out successfully',
          loggedOutDevices: 0,
          timestamp: new Date().toISOString()
        };
      }
    }

    @Get('admin/stats')
    @AuthAdmin() // ← NEW: Replaces all the boilerplate above!
    @ApiOperation({ 
      summary: 'Admin statistics endpoint',
      description: 'Example endpoint demonstrating @Auth() decorator - only admins can access'
    })
    @ApiResponse({ 
      status: 200, 
      description: 'System statistics',
      schema: {
        example: {
          totalUsers: 1500,
          activeUsers: 1200, 
          timestamp: '2024-01-01T00:00:00.000Z'
        }
      }
    })
    async getAdminStats(@CurrentUser() user: User) {
      // Example admin-only endpoint
      this.logger.log(`Admin stats accessed by user: ${user.id}`, {
        userId: user.id,
        role: user.role
      });

      return {
        totalUsers: 1500,
        activeUsers: 1200,
        totalTweets: 50000,
        timestamp: new Date().toISOString(),
        adminUser: user.username
      };
    }

  }