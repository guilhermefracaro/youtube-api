import { pool } from '../../../mysql'
import { v4 as uuidv4 } from 'uuid'
import { compare, hash } from 'bcrypt'
import { Request, Response } from 'express'
import { sign } from 'jsonwebtoken'

class VideoRepository {
    create(request: Request, response: Response) {
        const { title, description, user_id } = request.body

        pool.getConnection((err: any, connection: any) => {
            connection.query(
                'INSERT INTO videos (video_id, user_id, title, description) VALUES (?, ?, ?, ?)',
                [uuidv4(), user_id, title, description],
                (error: any, result: any, fileds: any) => {
                    connection.release()
                    if (error) {
                        return response.status(400).json(error)
                    }
                    response.status(200).json({ message: 'Vídeo enviado com sucesso!' })
                }
            )
        })
    }

    getVideos(request: Request, response: Response) {
        const { user_id } = request.query

        pool.getConnection((err: any, connection: any) => {
            connection.query(
                'SELECT * FROM videos WHERE user_id = ?',
                [user_id],
                (error: any, results: any, fileds: any) => {
                    connection.release()

                    if (error) {
                        return response.status(400).json({ error: "Erro ao buscar os vídeos!" })
                    }

                    return response.status(200).json({ message: 'Vídeos encontrados com sucesso!', videos: results })
                }
            )
        })
    }

    searchVideos(request: Request, response: Response) {
        const { search } = request.query

        pool.getConnection((err: any, connection: any) => {
            connection.query(
                'SELECT * FROM videos WHERE title LIKE ?',
                [`%${search}%`],
                (error: any, results: any, fileds: any) => {
                    connection.release()

                    if (error) {
                        return response.status(400).json({ error: "Erro ao buscar os vídeos!" })
                    }

                    return response.status(200).json({ message: 'Vídeos encontrados com sucesso!', videos: results })
                }
            )
        })
    }
}

export { VideoRepository }