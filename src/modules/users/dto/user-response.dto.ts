import { ApiProperty, OmitType } from '@nestjs/swagger';

export class UserResponseDto {
  @ApiProperty({ example: '12345' })
  id!: string;

  @ApiProperty({ example: 'davi_rinaldi' })
  username!: string;

  @ApiProperty({ type: String, format: 'date-time' })
  createdAt!: Date;
}

// Variante “pública” sem createdAt
export class UserPublicDto extends OmitType(UserResponseDto, ['createdAt'] as const) {}
