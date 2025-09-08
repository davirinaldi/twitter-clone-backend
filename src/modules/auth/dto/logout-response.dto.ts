import { ApiProperty } from '@nestjs/swagger';

export class LogoutResponseDto {
  @ApiProperty({ 
    description: 'Success message',
    example: 'Logged out successfully' 
  })
  message!: string;

  @ApiProperty({ 
    description: 'Number of devices logged out',
    example: 1 
  })
  loggedOutDevices!: number;

  @ApiProperty({ 
    description: 'Logout timestamp',
    example: '2024-01-01T00:00:00.000Z' 
  })
  timestamp!: string;
}