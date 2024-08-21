import { Router, Request, Response } from 'express';
import { User } from '../models/usersModel';
import { passwordEncrypt, passwordMatchCheck, generateLoginResponse } from '../services/usersService';
import clean from "clean-deep";
import { PipelineStage } from "mongoose";

/**
 * @swagger
 * tags:
 *   name: Users
 *   description: Users API
 */

/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - firstName
 *         - lastName
 *         - email
 *         - password
 *         - mobileNumber
 *       properties:
 *         firstName:
 *           type: string
 *           description: The user's firstName
 *         lastName:
 *           type: string
 *           description: The user's firstName
 *         email:
 *           type: string
 *           description: The user's email
 *         password:
 *           type: string
 *           description: The user's password
 *         mobileNumber:
 *           type: number
 *           description: The user's mobile number
 *       example:
 *         firstName: John 
 *         lastName: Doe
 *         email: john@example.com
 *         password: password
 *         mobileNumber: 9876543210
 */

/**
 * @swagger
 * /users/signUp:
 *   post:
 *     summary: Create a new user
 *     tags: [Users]
 *     parameters:
 *       - name: role
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *           enum: [USER, ADMIN, GUEST]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       201:
 *         description: User Signed Up successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       500:
 *         description: Error in user sign up
 */

export const userSignUp = async (req: Request, res: Response) => {
    try {
        req.body.password = await passwordEncrypt(req.body.password);
        const { firstName, lastName, email, password, mobileNumber } = req.body;
        const role = req.query.role;

        const user = new User({
            firstName, lastName, email, password, mobileNumber, role
        });

        await user.save();

        res.status(201).json({
            message: 'User Sign Up successfully Completed',
            user,
        });
    } catch (error) {
        res.status(500).json({ message: 'Error in user sign up', error });
    }
};

/**
 * @swagger
 * components:
 *   schemas:
 *     UserLogin:
 *       type: object
 *       required:
 *         - email
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           description: The user's email
 *         password:
 *           type: string
 *           description: The user's password
 *       example:
 *         email: john@example.com
 *         password: securepassword
 */

/**
 * @swagger
 * /users/login:
 *   post:
 *     summary: Login as any type user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UserLogin'
 *     responses:
 *       201:
 *         description: Logged in successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       500:
 *         description: Error in user login
 */

export const userLogin = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({
            email: email,
        });

        if (!user) throw new Error("User Not Found");

        const isValid = await passwordMatchCheck(req.body.password, user.password);
        if (!isValid) throw new Error("You have entered an invalid username/password.");

        const token = await generateLoginResponse(user);

        res.status(201).json({
            message: 'User Logged In successfully',
            token,
        });
    } catch (error) {
        res.status(500).json({ message: 'Error in user sign up', error });
    }
};


/**
 * @swagger
 * /users/list:
 *   get:
 *     summary: User List
 *     tags: [Users]
 *     parameters:
 *       - name: skip
 *         in: query
 *         schema:
 *           type: number
 *       - name: limit
 *         in: query
 *         schema:
 *           type: number
 *       - name: searchtext
 *         in: query
 *         schema:
 *           type: string
 *       - name: role
 *         in: query
 *         schema:
 *           type: string
 *           enum: [USER, ADMIN, GUEST]
 *       - name: sortorder
 *         in: query
 *         schema:
 *           type: string
 *           enum: [ASC, DESC]
 *       - name: sortkey
 *         in: query
 *         schema:
 *           type: string
 *           enum: [createdAt, updatedAt, firstName, email]
 *     responses:
 *       201:
 *         description: List Retrived successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       500:
 *         description: Error in getting user list 
 */

export const userList = async (req: Request, res: Response) => {
    try {        
        const limit = req.query.limit ? req.query.limit : 20;
        const skip = req.query.skip ? req.query.skip : 0;
        const { searchtext, role, sortorder } = req.query;
        const sortkey: any = req.query.sortkey ? req.query.sortkey : "createdAt";
        const sort: Record<string, | 1 | -1 | { $meta: "textScore" }> = {
            [sortkey]: sortorder ? (sortorder === "DESC" ? -1 : 1) : -1,
        };

        const aggregation = ([
            {
                $match: {
                    $or: searchtext ?
                        [
                            {
                                email: new RegExp(JSON.stringify(searchtext).replace(/[^a-zA-Z0-9 !@#\$%\^\&*\)\(+=._]/g, ""), "i"),
                            },
                            {
                                firstName: new RegExp(JSON.stringify(searchtext).replace(/[^a-zA-Z0-9 !@#\$%\^\&*\)\(+=._]/g, ""), "i"),
                            },
                            {
                                lastName: new RegExp(JSON.stringify(searchtext).replace(/[^a-zA-Z0-9 !@#\$%\^\&*\)\(+=._]/g, ""), "i"),
                            },
                        ] :
                        null,
                    role: role ?
                        {
                            $eq: role,
                        } : null
                },
            },
            {
                $project: {
                    email: 1,
                    firstName: 1,
                    lastName: 1,
                    fullName: {
                        $concat: ["$firstName", " ", "$lastName"],
                    },
                    country: 1,
                    status: 1,
                    role: 1,
                    createdAt: 1,
                    updatedAt: 1,
                    phoneNumber: 1,
                    profilePicture: 1,
                },
            },
            {
                $sort: sort,
            },
            {
                $facet: {
                    count: [
                        {
                            $count: "count",
                        },
                    ],
                    BoUser: [
                        {
                            $skip: skip,
                        },
                        {
                            $limit: limit,
                        },
                    ],
                },
            },
            {
                $addFields: {
                    count: {
                        $arrayElemAt: ["$count.count", 0],
                    },
                },
            },
        ]);
        const userDetail = await User.aggregate(clean(aggregation)).exec();
        if (!userDetail[0].count) {
            userDetail[0].count = 0
        }
        console.log("agg", userDetail)
        
        res.status(201).json({
            message: 'User Sign Up successfully Completed',
            list: userDetail[0],
        });
    } catch (error) {
        res.status(500).json({ message: 'Error in user sign up', error });
    }
};