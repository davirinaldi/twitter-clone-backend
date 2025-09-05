import { IsNotEmpty, IsString } from 'class-validator';

  export class LoginDto {
    @IsNotEmpty({ message: 'Identificador é obrigatório' })
    @IsString()
    identifier!: string; // email ou username

    @IsNotEmpty({ message: 'Senha é obrigatória' })
    @IsString()
    password!: string;
  }