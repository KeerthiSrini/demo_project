import express, { Request, Response } from 'express';
import mongoose from 'mongoose';
import { setupSwagger } from './swagger';
import userRoutes from './routes/index';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

setupSwagger(app);

app.use('/users', userRoutes);

mongoose.connect('mongodb://127.0.0.1:27017/demo').then(() => {
    console.log('Connected to MongoDB');
}).catch((error) => {
    console.log('Error connecting to MongoDB:', error);
});

app.get('/', (req: Request, res: Response) => {
    res.send('Hello, TypeScript with Express!');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

export default app;