import { IsOptional, IsBoolean } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LogoutDto {
  @ApiProperty({ 
    description: 'Logout from all devices',
    example: false,
    required: false 
  })
  @IsOptional()
  @IsBoolean()
  logoutAll?: boolean = false;
}